"""Execute the fixed volatile-patch AArch64 worker only inside Unicorn.

All syscalls address synthetic files and sparse Python bytearrays. The optional
bootstrap model stops before worker exec. No SDK, USB, host /proc, target
process or device execution is provided.
"""
import argparse
from collections import Counter
import hashlib
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import struct
import sys

import unicorn
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_INTR, UC_HOOK_BLOCK
from unicorn.arm64_const import UC_ARM64_REG_SP, UC_ARM64_REG_X0, UC_ARM64_REG_X8
from elftools.elf.elffile import ELFFile

from menu_window_profile import ROOT, MODULES, OBSERVATIONS, OBSERVATION_OFFSETS, OBSERVATION_SIZES, require, sha
from emulate_menu_window_offline import dirent

sys.path.insert(0, str(ROOT))
import camera_install_volatile as contract
from camera_menu_window import decode as decode_legacy

SUCCESS = {'success', 'start_short_reads', 'record_short_writes_completed'}
ADMISSION = {
    'not_root', 'low_tmpfs', 'wrong_tmpfs', 'inherited_fd', 'clock_backward', 'bad_start_nonce',
    'bad_start_version', 'half_start', 'missing_app', 'missing_lib',
    'inconsistent_versions', 'wrong_app_anchor', 'wrong_lib_anchor', 'duplicate_app',
    'app_maps_change_before_patch', 'lib_maps_change_before_patch', 'snapshot_before_error',
}
RESTORE_FAULTS = {'lib_restore_error', 'lib_restore_short', 'app_restore_error'}
PATCH_FAULTS = {'first_patch_error', 'first_patch_short', 'second_patch_error', 'second_patch_short'}
IDENTITY_FAULTS = {'app_pid_reused_after_patch', 'lib_maps_change_before_second_patch',
                   'lib_maps_change_after_patch', 'app_maps_change_after_both_patches'}
INTERRUPTED = {'terminate_after_first_patch', 'terminate_after_both_patches', 'terminate_after_patched'}
PUBLICATION_FAULTS = {name + '_' + fault for name in ('ready', 'patched', 'result')
                      for fault in ('open_error', 'write_error', 'zero_write', 'half_write_error', 'close_error')}
CASES = tuple(sorted(SUCCESS | ADMISSION | PATCH_FAULTS | RESTORE_FAULTS | IDENTITY_FAULTS | INTERRUPTED |
                     PUBLICATION_FAULTS | {'snapshot_end_error', 'app_mem_close_error', 'lib_mem_close_error',
                                           'result_publish_rename_error', 'result_destination_exists'}))


def emulate(directory, scenario, manifest):
    require(scenario in CASES, 'Unknown volatile model case')
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    elf = ELFFile(io.BytesIO((directory / 'worker.debug.elf').read_bytes()))
    pages = set()
    for segment in elf.iter_segments():
        if segment['p_type'] == 'PT_LOAD':
            pages.update(range(segment['p_vaddr'] & ~4095,
                               (segment['p_vaddr'] + segment['p_memsz'] + 4095) & ~4095, 4096))
    for page in sorted(pages):
        u.mem_map(page, 4096)
    for segment in elf.iter_segments():
        if segment['p_type'] == 'PT_LOAD':
            u.mem_write(segment['p_vaddr'], segment.data())
    sp = 0x90080000
    u.mem_map(0x90000000, 0x100000)
    u.reg_write(UC_ARM64_REG_SP, sp)
    u.mem_write(sp, struct.pack('<4Q', 2, sp + 256, sp + 300, 0))
    u.mem_write(sp + 256, b'worker\0')
    u.mem_write(sp + 300, b'123\0')
    nonce = bytes.fromhex(manifest['nonce'])
    job = manifest['job_dir']
    token = contract.START_MAGIC + nonce + struct.pack('<Q', contract.VERSION)
    if scenario == 'bad_start_nonce':
        token = token[:8] + bytes([token[8] ^ 1]) + token[9:]
    if scenario == 'bad_start_version':
        token = token[:24] + struct.pack('<Q', 1)
    if scenario == 'half_start':
        token = token[:16]
    files = {job + '/worker': b'SYNTHETIC_LOADED_WORKER', job + '/start': token}
    sentinel = b'PREEXISTING_RESULT_MUST_SURVIVE'
    if scenario == 'result_destination_exists':
        files[job + '/result'] = sentinel
    bases = {'lib': 0x40000000, 'app': 0x50000000}
    profiles = {'lib': MODULES['libupdaterufp.so'], 'app': MODULES['appFw.so']}
    memory = {name: {
        bases[name] + p['anchor_offset']: bytearray.fromhex(p['anchor_hex']),
        bases[name] + p['global_version_offset']: bytearray(
            (0x0602 if name == 'lib' else (6 << 16) | 2).to_bytes(p['version_bytes'], 'little')),
    } for name, p in profiles.items()}
    for offset, size in zip(OBSERVATION_OFFSETS, OBSERVATION_SIZES):
        memory['app'][bases['app'] + offset] = bytearray(size)
    if scenario == 'inconsistent_versions':
        memory['app'][bases['app'] + profiles['app']['global_version_offset']] = bytearray(struct.pack('<I', (6 << 16) | 1))
    for name in ('app', 'lib'):
        if scenario == 'wrong_' + name + '_anchor':
            memory[name][bases[name] + profiles[name]['anchor_offset']][0] ^= 1
    state = dict(next_fd=3, clock_ns=1000000000, exit=None, interrupted=False, blocks=0,
                 app_changed=False, lib_changed=False, app_mem_opened=False,
                 reads_split=0, short_writes=0, fault_injected=False, published=False)
    fds, writes, publications, trace = {}, [], [], []
    calls = Counter()
    block_digest = hashlib.sha256()

    def read_memory(name, address, count):
        require(0 < count <= 64, 'Unexpected synthetic memory read length')
        hits = [(base, raw) for base, raw in memory[name].items()
                if base <= address and address + count <= base + len(raw)]
        require(len(hits) == 1, 'Read outside synthetic sparse mm')
        base, raw = hits[0]
        return bytes(raw[address - base:address - base + count])

    def text(address):
        raw = bytes(u.mem_read(address, 512))
        require(b'\0' in raw, 'Unbounded syscall pathname')
        return raw.split(b'\0', 1)[0].decode('ascii')

    def ret(value):
        u.reg_write(UC_ARM64_REG_X0, value & ((1 << 64) - 1))

    def map_data(pid):
        if pid == 123:
            if scenario in ('missing_lib', 'clock_backward'):
                return b''
            inode = 113 if state['lib_changed'] else 112
            return (f'40000000-40008000 r-xp 00000000 00:01 {inode} /usr/lib/libupdaterufp.so\n'
                    '40025000-40026000 rw-p 00025000 00:01 112 /usr/lib/libupdaterufp.so\n').encode()
        if pid in (456, 457):
            if scenario == 'missing_app' or (pid == 457 and scenario != 'duplicate_app'):
                return b''
            inode = 115 if state['app_changed'] else 114
            return (f'50000000-53000000 r-xp 00000000 00:01 {inode} /usr/lib/appFw.so\n'
                    '57f00000-59000000 rw-p 07f00000 00:01 114 /usr/lib/appFw.so\n').encode()
        require(pid in (1, 234), 'Unexpected synthetic PID')
        return b''

    def record_name(path):
        name = path.rsplit('/', 1)[1]
        return 'result' if name == 'result.pending' else name

    def interrupt():
        state['interrupted'] = True
        trace.append(dict(event='model_interruption', memory_write_count=len(writes)))
        u.emu_stop()

    def syscall(_u, number, _data):
        require(number == 2, 'Only AArch64 SVC interrupt accepted')
        no = u.reg_read(UC_ARM64_REG_X8)
        a, b, c, d, e, f = [u.reg_read(UC_ARM64_REG_X0 + i) for i in range(6)]
        calls[no] += 1
        if no == 56:
            path = text(b)
            if c == 0x880c1:
                require(path in {job + '/' + n for n in ('ready', 'patched', 'result.pending')} and d == 0o600,
                        'Unexpected publication create')
                if scenario == record_name(path) + '_open_error':
                    state['fault_injected'] = True
                    ret(-5)
                    return
                if path in files:
                    ret(-17)
                    return
                files[path] = b''
                row = dict(kind='file', path=path, position=0, write=True)
                trace.append(dict(event='publication_open', file=record_name(path)))
            elif path in ('/proc', '/proc/self/fd'):
                require(c == 0x8c000, 'Unexpected directory flags')
                names = ['.', '1', '123', '234', '456']
                if scenario == 'duplicate_app':
                    names.append('457')
                if path == '/proc/self/fd':
                    names = ['.', str(state['next_fd'])] + (['999'] if scenario == 'inherited_fd' else [])
                row = dict(kind='directory', path=path, position=0, data=b''.join(dirent(n) for n in names))
            elif path.startswith('/proc/') and path.endswith('/maps'):
                require(c == 0x88000, 'Unexpected maps flags')
                pid = int(path.split('/')[2])
                if state['app_mem_opened']:
                    if scenario == 'app_maps_change_before_patch' and pid == 456:
                        state['app_changed'] = True
                    if scenario == 'lib_maps_change_before_patch' and pid == 123:
                        state['lib_changed'] = True
                row = dict(kind='maps', path=path, position=0, data=map_data(pid))
                trace.append(dict(event='maps_open', pid=pid, app_changed=state['app_changed'], lib_changed=state['lib_changed']))
            elif path in ('/proc/123/mem', '/proc/456/mem'):
                require(c == 0x88002, 'Unexpected proc mem flags')
                target = 'lib' if path == '/proc/123/mem' else 'app'
                state['app_mem_opened'] |= target == 'app'
                row = dict(kind='memory', path=path, target=target, mm_identity=target + '_original')
                trace.append(dict(event='memory_open', target=target))
            else:
                require(path == job + '/start' and c == 0x88000, 'Unexpected read path/flags')
                if path not in files:
                    ret(-2)
                    return
                row = dict(kind='file', path=path, position=0, write=False)
            fd = state['next_fd']
            state['next_fd'] += 1
            fds[fd] = row
            ret(fd)
        elif no == 57:
            row = fds.pop(a, None)
            error = 0 if row else -9
            if row:
                if row['kind'] == 'memory' and scenario == row['target'] + '_mem_close_error':
                    error = -5
                if row['kind'] == 'file' and scenario == record_name(row['path']) + '_close_error':
                    error = -5
                if error:
                    state['fault_injected'] = True
                trace.append(dict(event='close', kind=row['kind'], target=row.get('target'),
                                  file=row.get('path', '').rsplit('/', 1)[-1], returned=error))
                if row['kind'] == 'file' and row['path'] == job + '/patched' and scenario == 'terminate_after_patched':
                    ret(error)
                    interrupt()
                    return
            ret(error)
        elif no in (61, 63):
            require(a in fds, 'Read from unknown synthetic fd')
            row = fds[a]
            require(row['kind'] == 'directory' if no == 61 else row['kind'] in ('file', 'maps'), 'Read fd kind differs')
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
        elif no == 64:
            row = fds[a]
            require(row['kind'] == 'file' and row.get('write') and c <= contract.FRAME.size, 'Unexpected publication write')
            path, raw = row['path'], bytes(u.mem_read(b, c))
            name = record_name(path)
            count = c
            if scenario == name + '_write_error':
                count = -5
            elif scenario == name + '_zero_write':
                count = 0
            elif scenario == name + '_half_write_error':
                count = -5 if files[path] else c // 2
            elif scenario == 'record_short_writes_completed' and c > 31:
                count = 31
                state['short_writes'] += 1
            if scenario in {name + '_' + fault for fault in ('write_error', 'zero_write', 'half_write_error')}:
                state['fault_injected'] = True
            if count > 0:
                files[path] += raw[:count]
            publications.append(dict(record=name, requested=c, returned=count, cumulative_bytes=len(files[path])))
            trace.append(dict(event='publication_write', file=name, returned=count))
            ret(count)
        elif no == 35:
            path = text(b)
            require(path in (job + '/worker', job + '/start'), 'Unexpected unlink')
            ret(0 if files.pop(path, None) is not None else -2)
        elif no == 43:
            require(text(a) == '/tmp_wbshd', 'Unexpected statfs')
            free = 1 if scenario == 'low_tmpfs' else 100000
            u.mem_write(b, struct.pack('<15q', 0 if scenario == 'wrong_tmpfs' else 0x1021994,
                                      4096, 100000, free, free, 0, 0, 0, 255, 4096, 0, 0, 0, 0, 0))
            ret(0)
        elif no == 67:
            row = fds[a]
            require(row['kind'] == 'memory', 'pread to nonmemory fd')
            observation = row['target'] == 'app' and d in {bases['app'] + o for o in OBSERVATION_OFFSETS}
            fault = observation and ((scenario == 'snapshot_before_error' and not writes) or
                                     (scenario in ({'snapshot_end_error'} | RESTORE_FAULTS) and len(writes) == 2))
            if fault:
                state['fault_injected'] = True
                ret(-5)
            else:
                u.mem_write(b, read_memory(row['target'], d, c))
                ret(c)
        elif no == 68:
            require(not state['published'], 'Memory write after final publication')
            row = fds[a]
            require(row['kind'] == 'memory' and c == 4, 'Unexpected pwrite fd/count')
            target, raw = row['target'], bytes(u.mem_read(b, c))
            profile = profiles[target]
            require(d == bases[target] + profile['patch_offset'], 'pwrite outside fixed target')
            phase = 'patch' if raw.hex() == profile['patch_hex'] else 'restore'
            require(raw.hex() in (profile['patch_hex'], profile['original_hex']), 'Unexpected memory write bytes')
            if phase == 'patch':
                require(not any(w['target'] == target for w in writes), 'Repeated patch write forbidden')
            else:
                require(not (len(files.get(job + '/patched', b'')) == contract.FRAME.size and any(t['event'] == 'close' and t.get('file') == 'patched' and t['returned'] == 0 for t in trace)), 'Restoration after patched publication commit')
                require(not state[target + '_changed'], 'Restoration followed changed target identity')
            order = 'first' if target == 'app' else 'second'
            count = 4
            if phase == 'patch':
                count = -5 if scenario == order + '_patch_error' else 2 if scenario == order + '_patch_short' else 4
            elif scenario == target + '_restore_error':
                count = -5
                state['fault_injected'] = True
            elif scenario == target + '_restore_short':
                count = 2
                state['fault_injected'] = True
            before = read_memory(target, d, 4)
            if count > 0:
                base = bases[target] + profile['anchor_offset']
                offset = d - base
                memory[target][base][offset:offset + count] = raw[:count]
            writes.append(dict(target=target, phase=phase, address=hex(d), requested=4, returned=count,
                               before_hex=before.hex(), requested_hex=raw.hex(),
                               after_hex=read_memory(target, d, 4).hex(), fd_mm_identity=row['mm_identity']))
            trace.append(dict(event='pwrite', target=target, phase=phase, returned=count))
            if count == 4 and phase == 'patch':
                if target == 'app':
                    for index, size in enumerate(OBSERVATION_SIZES):
                        memory['app'][bases['app'] + OBSERVATION_OFFSETS[index]][:] = (index + 1).to_bytes(size, 'little')
                    if scenario == 'app_pid_reused_after_patch':
                        state['app_changed'] = True
                    if scenario == 'lib_maps_change_before_second_patch':
                        state['lib_changed'] = True
                else:
                    if scenario == 'lib_maps_change_after_patch':
                        state['lib_changed'] = True
                    if scenario == 'app_maps_change_after_both_patches':
                        state['app_changed'] = True
                if (target == 'app' and scenario == 'terminate_after_first_patch') or (target == 'lib' and scenario == 'terminate_after_both_patches'):
                    ret(count)
                    interrupt()
                    return
            ret(count)
        elif no == 276:
            old, new = text(b), text(d)
            require(a == ((1 << 64) - 100) and c == ((1 << 64) - 100) and e == 1
                    and old == job + '/result.pending' and new == job + '/result', 'Unexpected renameat2')
            require(not any(r['kind'] == 'memory' for r in fds.values()), 'Open memory descriptor at final publication')
            if scenario == 'result_publish_rename_error':
                state['fault_injected'] = True
                ret(-5)
            elif new in files:
                state['fault_injected'] = True
                ret(-17)
            else:
                require(old in files, 'Missing pending publication')
                files[new] = files.pop(old)
                state['published'] = True
                trace.append(dict(event='terminal_published', memory_write_count=len(writes)))
                ret(0)
        elif no in (175, 172, 173):
            ret((1000 if scenario == 'not_root' else 0) if no == 175 else 234 if no == 172 else 1)
        elif no == 113:
            require(a == 1, 'Unexpected clock id')
            now = 1000000000 if scenario == 'clock_backward' and calls[113] >= 3 else state['clock_ns']
            state['clock_ns'] += 100000000000
            u.mem_write(b, struct.pack('<2q', now // 1000000000, now % 1000000000))
            ret(0)
        elif no == 101:
            requested = struct.unpack('<2q', bytes(u.mem_read(a, 16)))
            require(requested[0] >= 0 and 0 <= requested[1] < 1000000000, 'Bad synthetic sleep')
            ret(0)
        elif no == 94:
            trace.append(dict(event='exit', code=a))
            state['exit'] = a
            u.emu_stop()
        else:
            raise RuntimeError('Unexpected volatile worker syscall ' + str(no))

    def block(_u, address, size, _data):
        state['blocks'] += 1
        block_digest.update(struct.pack('<QI', address, size))

    u.hook_add(UC_HOOK_INTR, syscall)
    u.hook_add(UC_HOOK_BLOCK, block)
    u.emu_start(elf['e_entry'], 0, count=6000000)
    require(state['exit'] is not None or state['interrupted'], 'Instruction budget exhausted')
    raws = {name: files.get(job + '/' + name, b'') for name in ('ready', 'patched', 'result', 'result.pending')}
    accepted, rejection, terminal = False, None, None
    if len(raws['result']) == contract.FRAME.size:
        terminal = dict(zip(contract.FIELDS, contract.FRAME.unpack(raws['result'])[2:]))
    try:
        contract.validate_publications(raws['ready'], raws['patched'], raws['result'], nonce=nonce, loader_pid=123)
        accepted = True
    except ValueError as error:
        rejection = str(error)
    legacy_rejected = True
    for raw in raws.values():
        if len(raw) == contract.FRAME.size:
            try:
                decode_legacy(raw, nonce)
            except ValueError:
                pass
            else:
                legacy_rejected = False
    require(legacy_rejected, 'Old decoder accepted a new publication')
    require(accepted == (scenario in SUCCESS), 'Success classification differs from declared case: ' + scenario)
    require((state['exit'] == 0) == accepted, 'Native exit and validated success disagree')
    patches = [w for w in writes if w['phase'] == 'patch']
    restores = [w for w in writes if w['phase'] == 'restore']
    require(len(patches) <= 2 and [w['target'] for w in patches] == ['app', 'lib'][:len(patches)], 'Wrong patch count/order')
    require(len(restores) <= 2 and [w['target'] for w in restores] in ([], ['app'], ['lib'], ['lib', 'app']), 'Wrong unwind order')
    if scenario in SUCCESS:
        require(len(writes) == 2 and all(w['returned'] == 4 for w in writes), 'Success requires two full patch writes')
        require(terminal['phase'] == 7 and terminal['restored'] == terminal['app_restored'] == terminal['hold_seconds'] == 0,
                'Success falsely claims restoration or a hold')
        require([terminal['before_' + n] for n in OBSERVATIONS] == [0] * 8 and
                [terminal['end_' + n] for n in OBSERVATIONS] == list(range(1, 9)), 'Snapshots missed patched app state')
    if scenario in ADMISSION or scenario.startswith('ready_'):
        require(not writes, 'Admission failure performed memory writes')
    if scenario in PATCH_FAULTS:
        require(patches[-1]['returned'] == (2 if scenario.endswith('_short') else -5), 'Patch fault missed')
        require(len(patches) == (1 if scenario.startswith('first') else 2), 'Patch continued after patch fault')
    if scenario in INTERRUPTED:
        require(state['interrupted'] and not state['published'] and not accepted, 'Interruption was not reached')
    if scenario in PUBLICATION_FAULTS or scenario in RESTORE_FAULTS or scenario.endswith('_mem_close_error') or scenario in {'snapshot_before_error', 'snapshot_end_error', 'result_publish_rename_error', 'result_destination_exists'}:
        require(state['fault_injected'], 'Declared fault was not injected')
    if scenario.endswith('_half_write_error'):
        name = scenario.removesuffix('_half_write_error')
        raw = raws['result.pending' if name == 'result' else name]
        require(len(raw) == contract.FRAME.size // 2, 'Partial publication bytes not retained')
    if scenario == 'start_short_reads':
        require(state['reads_split'] > 0, 'START splitting was not reached')
    if scenario == 'record_short_writes_completed':
        require(state['short_writes'] > 0, 'Record write splitting was not reached')
    if scenario == 'result_destination_exists':
        require(raws['result'] == sentinel and len(raws['result.pending']) == contract.FRAME.size, 'NOREPLACE did not preserve both records')
    final = {name: read_memory(name, bases[name] + p['patch_offset'], 4).hex() for name, p in profiles.items()}
    expected = {name: p['original_hex'] for name, p in profiles.items()}
    retains_both = (scenario in SUCCESS or scenario.startswith('result_') or
                    scenario.endswith('_mem_close_error') or scenario in {'terminate_after_both_patches', 'terminate_after_patched'})
    if retains_both:
        expected = {name: p['patch_hex'] for name, p in profiles.items()}
    if scenario in {'app_pid_reused_after_patch', 'app_maps_change_after_both_patches', 'terminate_after_first_patch', 'app_restore_error'}:
        expected['app'] = profiles['app']['patch_hex']
    if scenario in {'lib_maps_change_after_patch', 'lib_restore_error'}:
        expected['lib'] = profiles['lib']['patch_hex']
    if scenario == 'lib_restore_short':
        expected['lib'] = profiles['lib']['original_hex'][:4] + profiles['lib']['patch_hex'][4:]
    require(final == expected, 'Final synthetic memory state differs: ' + scenario)

    classification = ('VOLATILE_PATCH_APPLIED_NOT_RESTORED' if accepted else
                      'REFUSED_ZERO_MEMORY_WRITES' if not writes else
                      'MODEL_UNWOUND_FAILURE' if all(final[n] == profiles[n]['original_hex'] for n in final) else
                      'UNKNOWN_MEMORY_OR_PUBLICATION')
    return dict(case=scenario, passed=True, classification=classification, actual_native_instruction_execution=True, accepted_success=accepted, decoder_rejection=rejection,
                legacy_decoder_rejected=legacy_rejected, native_exit=state['exit'], model_interrupted=state['interrupted'],
                instruction_budget=6000000, native_basic_blocks_executed=state['blocks'],
                basic_block_trace_sha256=block_digest.hexdigest(), trace=trace, memory_writes=writes,
                final_synthetic_mm_bytes=final, publication_write_events=publications,
                publication_hex={n: raw.hex() for n, raw in raws.items()}, native_terminal=terminal,
                open_memory_fds_at_exit=sum(r['kind'] == 'memory' for r in fds.values()),
                syscall_counts=dict(sorted(calls.items())), hardware_operations=0)


def bootstrap_report(job, manifest, destination):
    from model_toolchain_bootstraps_offline import module_info, CASES as BOOTSTRAP_CASES, PINS
    from emulate_stream_bootstrap import emulate as emulate_bootstrap
    for relative, expected in PINS.items():
        require(sha(ROOT / relative) == expected, 'Pinned bootstrap source/model changed: ' + relative)
    module_raw, worker_raw = (job / 'libJit.so').read_bytes(), (job / 'worker.elf').read_bytes()
    module = module_info(module_raw)
    require(module_raw.count(worker_raw) == 1, 'New worker not embedded exactly once')
    adapter = dict(schema='MODEL_ONLY_BOOTSTRAP_ADAPTER_NOT_A_RELEASE/1', model_fixture_only=True,
                   admission='MODEL_ONLY_NO_DEVICE_PERMISSION', body_binding=None,
                   nonce=manifest['nonce'], job_dir=manifest['job_dir'], module=module,
                   compact_worker_sha256=hashlib.sha256(worker_raw).hexdigest(),
                   metadata_source_sha256=sha(job / 'manifest.json'))
    before = {name: sha(job / name) for name in ('manifest.json', 'verification.json', 'libJit.so', 'worker.elf')}
    with TemporaryDirectory(prefix='install-volatile-MODEL-ONLY-', dir=ROOT / 'output') as name:
        fixture = Path(name)
        (fixture / 'libJit.so').write_bytes(module_raw)
        (fixture / 'worker.elf').write_bytes(worker_raw)
        (fixture / 'bootstrap.json').write_text(json.dumps(adapter))
        cases = [emulate_bootstrap(fixture, scenario) for scenario in BOOTSTRAP_CASES]
    require(len(cases) == 16 and all(c['passed'] for c in cases), 'Bootstrap matrix incomplete')
    require([c['scenario'] for c in cases if c['exec_observed_not_executed']] == ['grandchild_exec'], 'Exec observation boundary differs')
    require(before == {name: sha(job / name) for name in before}, 'Bootstrap inputs changed')
    report = dict(schema='camera-install-volatile-bootstrap-actual-artifact-model/1', all_passed=True,
                  case_count=len(cases), cases=cases, module=module, model_only_adapter=adapter,
                  input_hashes=before, pinned_source_and_model_hashes=PINS,
                  adapter_helper_sha256=sha(ROOT / 'tools/model_toolchain_bootstraps_offline.py'),
                  runner_sha256=sha(Path(__file__)), bootstrap_CPU_emulated=True,
                  worker_executed=False, real_ARM_process_executed=False, hardware_operations=0,
                  original_inputs_unchanged=True,
                  limitations=['Fork branches are separate injected return paths, not concurrent scheduler execution',
                               'Execve verifies exact embedded bytes and argv then stops before executing the worker',
                               'No live loader, SDK, USB, device, cache or installation acceptance'])
    destination = destination.absolute()
    require(destination.is_relative_to(ROOT / 'output') and not any(p.is_symlink() for p in (destination, *destination.parents)), 'Non-symlink bootstrap report path required')
    with destination.open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps(dict(bootstrap_report=str(destination), cases=16, all_passed=True)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--job', type=Path, required=True)
    parser.add_argument('--case', choices=CASES, action='append')
    parser.add_argument('--report', type=Path)
    parser.add_argument('--bootstrap-report', type=Path)
    args = parser.parse_args()
    from verify_install_volatile_offline import verify
    job = args.job.absolute()
    verify(job)
    manifest = json.loads((job / 'manifest.json').read_text())
    original = {name: sha(job / name) for name in ('manifest.json', 'verification.json')}
    require(manifest['result']['magic'] == contract.MAGIC.decode() and manifest['result']['fields'] == list(contract.FIELDS), 'Contract and compiled asset ABI differ')
    selected = tuple(args.case) if args.case else CASES
    require(len(set(selected)) == len(selected), 'Duplicate cases')
    results = []
    for case in selected:
        results.append(emulate(job, case, manifest))
        print(case + ' PASS', flush=True)
    verify(job)
    require(original == {name: sha(job / name) for name in original}, 'Original manifest/verification changed')
    report = dict(schema='camera-install-volatile-real-worker-synthetic-syscalls/1', all_passed=True,
        coverage_complete_for_declared_matrix=set(selected) == set(CASES), case_count=len(results), declared_cases=list(CASES), cases=results,
        engine=dict(name='Unicorn', version=unicorn.__version__, target='AArch64'),
        execution_kind='EMULATED_INSTRUCTIONS_ONLY', actual_compiled_A64_instructions=True,
        real_ARM_process_executed=False, bootstrap_executed=False, hardware_operations=0,
        admission='OFFLINE_NOT_BODY_BOUND', runtime_executor_created=False, workflow_unlocked=False,
        manifest_sha256=original['manifest.json'], verification_sha256=original['verification.json'],
        verifier_sha256=sha(ROOT / 'tools/verify_install_volatile_offline.py'),
        emulator_sha256=sha(Path(__file__)), decoder_sha256=sha(ROOT / 'camera_install_volatile.py'),
        contract_sha256=sha(ROOT / 'camera_install_volatile.py'), native_fault_model_executed=True,
        legacy_decoder_sha256=sha(ROOT / 'camera_menu_window.py'),
        fixture_helper_sha256=sha(ROOT / 'tools/emulate_menu_window_offline.py'),
        profile_sha256=sha(ROOT / 'tools/install_volatile_profile.py'),
        base_profile_sha256=sha(ROOT / 'tools/menu_window_profile.py'),
        source_bindings=manifest['sources'], artifact_bindings=manifest['artifacts'],
        debug_worker_sha256=sha(job / 'worker.debug.elf'),
        assumptions=['Exact fixed synthetic /proc PIDs, map rows and sparse mm ranges only',
                     'PIDs/maps identity changes retain the original synthetic mm behind an open fd',
                     'Finite synchronous syscall returns; synthetic monotonic clock advances 100 seconds per call',
                     'Precommit failures may attempt bounded pinned-mm reverse unwind; success never restores',
                     'A close error removes the synthetic fd and reports EIO; no close retry is modeled',
                     'Model interruption stops immediately at a chosen syscall boundary'],
        limitations=['No real target scheduling, simultaneous instruction execution, cache coherence or four-byte atomicity evidence',
                     'No real Linux /proc permissions, COW, PID lifetime, tmpfs durability, signals, power loss or indefinite blocking',
                     'No bootstrap constructor, SDK, USB, device, package/updater or installation execution',
                     'Success validates publication bytes and ordering only within the synthetic syscall model',
                     'NOREPLACE failures preserve synthetic pending bytes; no host collector or recovery executor is tested'])
    destination = (args.report or job / 'native-model-report.json').absolute()
    require(destination.is_relative_to(ROOT / 'output') and not any(p.is_symlink() for p in (destination, *destination.parents)), 'Non-symlink output report path required')
    with destination.open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps(dict(report=str(destination), cases=len(results), all_passed=True)))
    if args.bootstrap_report is not None:
        bootstrap_report(job, manifest, args.bootstrap_report)


if __name__ == '__main__':
    main()
