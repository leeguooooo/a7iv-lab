"""Independently inspect one-shot patch artifacts; never build or access devices."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import struct
import sys

from elftools.elf.elffile import ELFFile
sys.path.insert(0, str(Path(__file__).resolve().parent))
from install_volatile_profile import (ROOT, APP, COMPILER, COMPILER_SHA, DEFS, MODULES,
    OBSERVATION_OFFSETS, OBSERVATION_SIZES, FIELDS, BASE_FIELDS, APP_FIELDS, STATUS_FIELDS,
    MAGIC, VERSION, START_MAGIC, START_VERSION, SCHEMA, PROFILE,
    input_evidence, read_regular, require, sha, mapped)
from verify_menu_window_offline import inspect_elf, check_compact


def check_header(raw, nonce, job_dir):
    lines = raw.decode('ascii').splitlines()
    expected_defs = dict(DEFS, JOB_DIR='"' + job_dir + '"')
    defines, arrays = {}, {}
    for line in lines:
        define = re.fullmatch(r'#define (\w+) (.+)', line)
        array = re.fullmatch(r'static const (unsigned char|unsigned long) (\w+)\[\]=\{([0-9,]+)\};', line)
        require(bool(define) != bool(array), 'Unknown generated header syntax')
        if define:
            key, value = define.groups()
            require(key not in defines, 'Duplicate define')
            defines[key] = value if key == 'JOB_DIR' else int(value)
        else:
            kind, key, values = array.groups()
            require(key not in arrays, 'Duplicate array')
            arrays[key] = (kind, tuple(map(int, values.split(','))))
    expected_arrays = {'job_nonce': ('unsigned char', tuple(bytes.fromhex(nonce))),
        'observation_offsets': ('unsigned long', OBSERVATION_OFFSETS),
        'observation_sizes': ('unsigned long', OBSERVATION_SIZES)}
    for name, prefix in (('libupdaterufp.so', ''), ('appFw.so', 'app_')):
        for key, suffix in (('anchor_hex', 'anchor'), ('original_hex', 'original4'), ('patch_hex', 'patch4')):
            expected_arrays[prefix + suffix] = ('unsigned char', tuple(bytes.fromhex(MODULES[name][key])))
    require(defines == expected_defs and arrays == expected_arrays, 'Generated header differs from fixed profile/nonce')
    return {'defines': len(defines), 'arrays': len(arrays), 'nonce_and_profile_checked': True}


def check_abi(debug):
    elf = ELFFile(io.BytesIO(debug))
    symbols = elf.get_section_by_name('.symtab')
    require(symbols is not None, 'Debug symbols absent')
    values = {s.name: s['st_value'] for s in symbols.iter_symbols() if s.name}
    wr = [s for s in symbols.iter_symbols() if s.name == 'wr']
    require(len(wr) == 1 and wr[0]['st_size'] == 432, 'Native result symbol is not 432 bytes')
    require(elf['e_entry'] == values.get('_start'), 'Worker entry does not bind _start')
    require(elf.has_dwarf_info(), 'DWARF ABI evidence missing')
    structs = [die for cu in elf.get_dwarf_info().iter_CUs() for die in cu.iter_DIEs()
               if die.tag == 'DW_TAG_structure_type' and
               die.attributes.get('DW_AT_name') and die.attributes['DW_AT_name'].value == b'InstallVolatileResult']
    require(len(structs) == 1 and structs[0].attributes['DW_AT_byte_size'].value == 432,
            'DWARF InstallVolatileResult ABI changed')
    members = [(d.attributes['DW_AT_name'].value.decode(),
                d.attributes['DW_AT_data_member_location'].value)
               for d in structs[0].iter_children() if d.tag == 'DW_TAG_member']
    scalar = BASE_FIELDS + APP_FIELDS + STATUS_FIELDS
    expected = [('magic', 0), ('nonce', 8)] + [(name, 24 + 8 * i) for i, name in enumerate(scalar)]
    expected += [('before', 24 + len(scalar) * 8), ('end', 24 + len(scalar) * 8 + 64)]
    require(members == expected and struct.calcsize('<8s16s51q') == 432 and len(FIELDS) == 51,
            'DWARF member offsets or wire layout changed')
    return {'bytes': 432, 'symbol_size_verified': True, 'dwarf_members': members}, values

def check_worker_identity(debug, nonce, job_dir, symbols):
    elf = ELFFile(io.BytesIO(debug))
    nonce_address = symbols.get('job_nonce')
    require(isinstance(nonce_address, int), 'Worker nonce symbol absent')
    offset = mapped(elf, nonce_address, 16)
    require(debug[offset:offset + 16] == bytes.fromhex(nonce), 'Compiled worker nonce differs')
    loaded = b''.join(segment.data() for segment in elf.iter_segments() if segment['p_type'] == 'PT_LOAD')
    require(MAGIC.encode() in loaded and START_MAGIC.encode() in loaded and job_dir.encode() in loaded,
            'Compiled worker protocol strings differ')
    require(b'M4DWL002' not in loaded and b'M4DSTART' not in loaded and 'hold_window' not in symbols
            and 'install_main' in symbols, 'Legacy protocol/lifetime present in install worker')
    return {'nonce_in_loaded_bytes': True, 'protocol_strings_in_loaded_bytes': True,
            'legacy_protocol_absent': True, 'native_version_execution_requires_fault_model': True}


def check_commands(commands, directory):
    common = ['-target', 'aarch64-linux-gnu', '-mcpu=generic', '-Os', '-g',
        '-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-fno-unwind-tables',
        '-fno-asynchronous-unwind-tables', '-nostdlib', '-ffunction-sections', '-fdata-sections',
        '-Wl,--gc-sections', '-Wl,--no-undefined', '-Wl,--build-id=none', '-Wl,-z,noexecstack',
        '-Wl,-z,max-page-size=4096', '-Wl,-z,common-page-size=4096',
        '-I', str(directory), '-I', str(APP / 'native'), '-I', str(APP / 'workflow')]
    expected = [[str(COMPILER), 'cc', *common, '-static', '-fno-pic', '-Wl,-e,_start',
                 str(ROOT / 'native/install_volatile_patch.c'), '-o', str(directory / 'worker.debug.elf')],
                [str(COMPILER), 'cc', *common, '-shared', '-fPIC', '-Wl,-Bsymbolic', '-s',
                 str(APP / 'native/bootstrap.c'), '-o', str(directory / 'libJit.so')]]
    require(commands == expected, 'Recorded build commands differ from closed source/profile set')


def verify(directory):
    directory = Path(directory).absolute()
    require('..' not in directory.parts and directory.is_relative_to(ROOT / 'output'),
            'Only workspace output artifacts admitted')
    manifest_raw = read_regular(directory / 'manifest.json')
    m = json.loads(manifest_raw)
    require(m['schema'] == SCHEMA and
            m['profile'] == PROFILE and m['admission'] == 'OFFLINE_NOT_BODY_BOUND',
            'Offline profile/admission changed')
    for key in ('live_controller_sealed', 'hardware_acceptance', 'native_fault_model_executed',
                'worker_executed', 'bootstrap_executed', 'automatic_retry'):
        require(m[key] is False, 'Unsupported execution/admission claim')
    require(m['body_binding'] is None and m['target_package_sha256'] is None and
            type(m['hardware_operations']) is int and m['hardware_operations'] == 0, 'Offline boundary changed')
    nonce = m['nonce']
    require(isinstance(nonce, str) and re.fullmatch('[0-9a-f]{32}', nonce) and any(bytes.fromhex(nonce)), 'Bad nonce')
    require(m['job_dir'] == '/tmp_wbshd/m4ivp_' + nonce, 'Nonce/directory mismatch')
    sources, libraries = input_evidence()
    require(m['sources'] == sources and m['libraries'] == libraries, 'Independent source/ELF evidence mismatch')
    require(m['compiler'] == {'path': str(COMPILER.relative_to(ROOT)), 'sha256': COMPILER_SHA,
            'version': '0.15.2', 'host': 'aarch64-macos', 'target': 'aarch64-linux-gnu'}, 'Compiler profile differs')
    check_commands(m['compile_commands'], directory)
    require(m['result'] == {'magic': MAGIC, 'version': VERSION, 'start_magic': START_MAGIC,
            'start_version': START_VERSION, 'format': '<8s16s51q', 'bytes': 432, 'fields': list(FIELDS)}, 'Result schema differs')
    require(m['timeouts'] == {'start': 120, 'maps_wait': 300} and
            m['patch_order'] == ['app', 'lib'] and
            m['partial_failure_restore_order'] == ['lib', 'app'] and m['success_phase'] == 7 and
            m['success_restores_RAM'] is False and m['success_requires_closed_mem_fds'] is True and
            m['terminal_publication'] == {'pending': 'result.pending', 'published': 'result',
                                          'syscall': 'renameat2', 'flags': 1}, 'Lifecycle metadata differs')
    names = {'job.h', 'worker.debug.elf', 'worker.elf', 'worker_blob.h', 'symbols.json', 'libJit.so',
             'worker.debug.elf.compile.log', 'libJit.so.compile.log'}
    require(set(m['artifacts']) == names, 'Artifact closure differs')
    artifacts = {name: read_regular(directory / name) for name in names}
    for name, raw in artifacts.items():
        require(m['artifacts'][name] == {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()},
                'Artifact digest/length differs: ' + name)
    header = check_header(artifacts['job.h'], nonce, m['job_dir'])
    debug, compact, module = (artifacts[n] for n in ('worker.debug.elf', 'worker.elf', 'libJit.so'))
    inspected = {'worker_debug': inspect_elf(debug, True),
                 'worker_compact': inspect_elf(compact, True, compact=True),
                 'bootstrap': inspect_elf(module, False)}
    loaded = check_compact(debug, compact)
    abi, symbols = check_abi(debug)
    identity = check_worker_identity(debug, nonce, m['job_dir'], symbols)
    require(json.loads(artifacts['symbols.json']) == symbols, 'Saved symbol map differs from debug ELF')
    blob_text = artifacts['worker_blob.h'].decode('ascii')
    match = re.fullmatch(r'static const unsigned char worker_blob\[\]=\{([0-9,]+)\};\n', blob_text)
    require(match and bytes(map(int, match.group(1).split(','))) == compact, 'Embedded header differs from compact worker')
    require(len(module) <= 65520 and module.count(compact) == 1, 'Single embedded worker/upload bound failed')
    module_elf = ELFFile(io.BytesIO(module))
    position = module.index(compact)
    containing = [s for s in module_elf.iter_segments() if s['p_type'] == 'PT_LOAD' and
                  s['p_offset'] <= position and position + len(compact) <= s['p_offset'] + s['p_filesz']]
    require(len(containing) == 1 and not containing[0]['p_flags'] & 2, 'Worker blob must be in one nonwritable load segment')
    return {'schema': 'camera-install-volatile-offline-verification/1', 'all_passed': True,
            'manifest_sha256': hashlib.sha256(manifest_raw).hexdigest(), 'nonce': nonce,
            'profile': m['profile'], 'admission': 'OFFLINE_NOT_BODY_BOUND',
            'source_count': len(sources), 'saved_library_checks': libraries,
            'header': header, 'worker_identity': identity, 'elf': inspected, 'compact_loaded_bytes': loaded, 'result_abi': abi,
            'embedded_worker_count': 1, 'embedded_worker_file_offset': position,
            'module_upload_bound': 65520, 'hardware_operations': 0, 'hardware_acceptance': False,
            'native_fault_model_executed': False, 'worker_executed': False, 'bootstrap_executed': False,
            'verifier_sha256': sha(Path(__file__)),
            'limitations': m['limitations']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.output)
    destination = args.output / 'verification.json'
    with destination.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'all_passed': True, 'report': str(destination),
                      'module_bytes': result['elf']['bootstrap']['bytes'], 'hardware_operations': 0,
                      'admission': result['admission'], 'native_fault_model_executed': False}))


if __name__ == '__main__':
    main()
