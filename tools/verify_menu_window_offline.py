"""Independently inspect saved stock menu artifacts; no build or device execution."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import struct

from elftools.elf.elffile import ELFFile
from menu_window_profile import (ROOT, APP, COMPILER, COMPILER_SHA, DEFS, MODULES,
    OBSERVATION_OFFSETS, OBSERVATION_SIZES, FIELDS, BASE_FIELDS, APP_FIELDS, STATUS_FIELDS,
    input_evidence, read_regular, require, sha, mapped)


def inspect_elf(raw, executable, *, compact=False):
    elf = ELFFile(io.BytesIO(raw))
    require(elf.elfclass == 64 and elf.little_endian and elf['e_machine'] == 'EM_AARCH64'
            and elf['e_type'] == ('ET_EXEC' if executable else 'ET_DYN'), 'Artifact ELF identity changed')
    segments = list(elf.iter_segments())
    require(not any(s['p_type'] == 'PT_INTERP' for s in segments), 'Unexpected dynamic interpreter')
    loads = [s for s in segments if s['p_type'] == 'PT_LOAD']
    require(loads and all(s['p_filesz'] <= s['p_memsz'] and
            s['p_offset'] + s['p_filesz'] <= len(raw) and s['p_flags'] & 3 != 3 for s in loads),
            'Invalid or writable-executable load segment')
    stacks = [s for s in segments if s['p_type'] == 'PT_GNU_STACK']
    require(len(stacks) == 1 and not stacks[0]['p_flags'] & 1, 'Executable/absent stack policy')
    for index, first in enumerate(loads):
        for second in loads[index + 1:]:
            require(first['p_vaddr'] + first['p_memsz'] <= second['p_vaddr'] or
                    second['p_vaddr'] + second['p_memsz'] <= first['p_vaddr'], 'Overlapping load segments')
    imports, deps, relocs, init = [], [], [], None
    for section in elf.iter_sections():
        if section['sh_type'] in ('SHT_SYMTAB', 'SHT_DYNSYM'):
            imports.extend(s.name for s in section.iter_symbols()
                           if s.name and s['st_shndx'] == 'SHN_UNDEF')
        if section['sh_type'] == 'SHT_DYNAMIC':
            for tag in section.iter_tags():
                require(tag.entry.d_tag != 'DT_TEXTREL', 'Text relocations forbidden')
                if tag.entry.d_tag == 'DT_NEEDED':
                    deps.append(tag.needed)
                if tag.entry.d_tag == 'DT_INIT':
                    init = tag.entry.d_val
        if section['sh_type'] in ('SHT_RELA', 'SHT_REL'):
            relocs.extend(int(r.entry.r_info_type) for r in section.iter_relocations())
    require(not imports and not deps, 'Unexpected imports/dependencies')
    require(not relocs if executable else all(r == 1027 for r in relocs), 'Unexpected relocation type')
    if executable:
        mapped(elf, elf['e_entry'], 4, executable=True)
    else:
        require(init is not None, 'Bootstrap DT_INIT absent')
        mapped(elf, init, 4, executable=True)
    if compact:
        require(elf['e_shoff'] == elf['e_shentsize'] == elf['e_shnum'] == elf['e_shstrndx'] == 0,
                'Compact section-table fields must be zero')
    return {'type': elf['e_type'], 'entry': elf['e_entry'], 'dt_init': init,
            'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'undefined_imports': imports, 'dependencies': deps, 'relocations': relocs,
            'loads': [dict(s.header) for s in loads]}


def check_compact(debug, compact):
    de, ce = ELFFile(io.BytesIO(debug)), ELFFile(io.BytesIO(compact))
    dl = [s for s in de.iter_segments() if s['p_type'] == 'PT_LOAD']
    cl = [s for s in ce.iter_segments() if s['p_type'] == 'PT_LOAD']
    require(len(dl) == len(cl) and dl, 'Load segment count changed')
    require(de['e_entry'] == ce['e_entry'], 'Entry changed')
    limit = max(s['p_offset'] + s['p_filesz'] for s in dl)
    require(len(compact) == limit, 'Compact boundary differs')
    expected = bytearray(debug[:limit])
    expected[40:48] = b'\0' * 8
    expected[58:64] = b'\0' * 6
    require(bytes(expected) == compact, 'Compact bytes changed beyond permitted section-header fields')
    for original, short in zip(dl, cl):
        require(dict(original.header) == dict(short.header), 'PT_LOAD header differs')
        start, end = original['p_offset'], original['p_offset'] + original['p_filesz']
        require(short.data() == expected[start:end], 'PT_LOAD payload differs')
    return {'load_segments': len(dl), 'all_loaded_bytes_checked': True,
            'allowed_header_change_ranges': [[40, 48], [58, 64]], 'compact_bytes': limit}


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
               die.attributes.get('DW_AT_name') and die.attributes['DW_AT_name'].value == b'DualResult']
    require(len(structs) == 1 and structs[0].attributes['DW_AT_byte_size'].value == 432,
            'DWARF DualResult ABI changed')
    members = [(d.attributes['DW_AT_name'].value.decode(),
                d.attributes['DW_AT_data_member_location'].value)
               for d in structs[0].iter_children() if d.tag == 'DW_TAG_member']
    scalar = BASE_FIELDS + APP_FIELDS + STATUS_FIELDS
    expected = [('magic', 0), ('nonce', 8)] + [(name, 24 + 8 * i) for i, name in enumerate(scalar)]
    expected += [('before', 24 + len(scalar) * 8), ('end', 24 + len(scalar) * 8 + 64)]
    require(members == expected and struct.calcsize('<8s16s51q') == 432 and len(FIELDS) == 51,
            'DWARF member offsets or wire layout changed')
    return {'bytes': 432, 'symbol_size_verified': True, 'dwarf_members': members}, values


def verify(directory):
    directory = Path(directory).absolute()
    require(directory.is_relative_to(ROOT / 'output'), 'Only workspace output artifacts admitted')
    manifest_raw = read_regular(directory / 'manifest.json')
    m = json.loads(manifest_raw)
    require(m['schema'] == 'camera-menu-stock-window-offline/1' and
            m['profile'] == 'menu_stock_6.02_saved_ELFs' and m['admission'] == 'OFFLINE_NOT_BODY_BOUND',
            'Offline profile/admission changed')
    for key in ('live_controller_sealed', 'hardware_acceptance', 'native_fault_model_executed',
                'worker_executed', 'bootstrap_executed', 'automatic_retry'):
        require(m[key] is False, 'Unsupported execution/admission claim')
    require(m['body_binding'] is None and m['target_package_sha256'] is None and
            type(m['hardware_operations']) is int and m['hardware_operations'] == 0, 'Offline boundary changed')
    nonce = m['nonce']
    require(isinstance(nonce, str) and re.fullmatch('[0-9a-f]{32}', nonce) and any(bytes.fromhex(nonce)), 'Bad nonce')
    require(m['job_dir'] == '/tmp_wbshd/m4dual_' + nonce, 'Nonce/directory mismatch')
    sources, libraries = input_evidence()
    sources.update({str(p.relative_to(ROOT)): sha(p) for p in (
        ROOT / 'tools/build_menu_window_offline.py', ROOT / 'tools/menu_window_profile.py', Path(__file__))})
    require(m['sources'] == sources and m['libraries'] == libraries, 'Independent source/ELF evidence mismatch')
    require(m['compiler'] == {'path': str(COMPILER.relative_to(ROOT)), 'sha256': COMPILER_SHA,
            'version': '0.15.2', 'host': 'aarch64-macos', 'target': 'aarch64-linux-gnu'}, 'Compiler profile differs')
    require(m['result'] == {'magic': 'M4DWL002', 'start_magic': 'M4DSTART', 'format': '<8s16s51q',
            'bytes': 432, 'fields': list(FIELDS)}, 'Result schema differs')
    require(m['timeouts'] == {'start': 120, 'maps_wait': 300, 'hold': 600} and
            m['patch_order'] == ['app', 'lib'] and m['restore_order'] == ['lib', 'app'], 'Lifecycle metadata differs')
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
    return {'schema': 'camera-menu-stock-window-offline-verification/1', 'all_passed': True,
            'manifest_sha256': hashlib.sha256(manifest_raw).hexdigest(), 'nonce': nonce,
            'profile': m['profile'], 'admission': 'OFFLINE_NOT_BODY_BOUND',
            'source_count': len(sources), 'saved_library_checks': libraries,
            'header': header, 'elf': inspected, 'compact_loaded_bytes': loaded, 'result_abi': abi,
            'embedded_worker_count': 1, 'embedded_worker_file_offset': position,
            'module_upload_bound': 65520, 'hardware_operations': 0, 'hardware_acceptance': False,
            'native_fault_model_executed': False, 'worker_executed': False, 'bootstrap_executed': False,
            'verifier_sha256': sha(Path(__file__)),
            'limitations': m['limitations']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'output/menu-stock-window-offline-01')
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
