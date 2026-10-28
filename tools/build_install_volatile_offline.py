"""Build fresh offline one-shot patch artifacts; no device or installer action."""
import argparse
import io
import json
import os
from pathlib import Path
import secrets
import struct
import sys
import subprocess

from elftools.elf.elffile import ELFFile
sys.path.insert(0, str(Path(__file__).resolve().parent))
from install_volatile_profile import (ROOT, APP, COMPILER, COMPILER_SHA, DEFS, MODULES,
    OBSERVATION_OFFSETS, OBSERVATION_SIZES, FIELDS, MAGIC, VERSION, START_MAGIC,
    START_VERSION, SCHEMA, PROFILE, input_evidence, require, sha)


def array(name, values, ctype='unsigned char'):
    return 'static const ' + ctype + ' ' + name + '[]={' + ','.join(map(str, values)) + '};\n'


def build(output):
    sources, libraries = input_evidence()
    output = Path(output).absolute()
    require('..' not in output.parts and output.is_relative_to(ROOT / 'output') and not output.exists(),
            'Fresh output under workspace/output required')
    require(not any(p.is_symlink() for p in output.parents), 'Symlink output forbidden')
    output.mkdir(mode=0o700, parents=True)
    nonce = secrets.token_bytes(16)
    job_dir = '/tmp_wbshd/m4ivp_' + nonce.hex()
    header = '#define JOB_DIR "' + job_dir + '"\n'
    header += ''.join(f'#define {key} {value}\n' for key, value in DEFS.items())
    header += array('job_nonce', nonce)
    for module, prefix in (('libupdaterufp.so', ''), ('appFw.so', 'app_')):
        for key, suffix in (('anchor_hex', 'anchor'), ('original_hex', 'original4'), ('patch_hex', 'patch4')):
            header += array(prefix + suffix, bytes.fromhex(MODULES[module][key]))
    header += array('observation_offsets', OBSERVATION_OFFSETS, 'unsigned long')
    header += array('observation_sizes', OBSERVATION_SIZES, 'unsigned long')
    (output / 'job.h').write_text(header)
    common = ['-target', 'aarch64-linux-gnu', '-mcpu=generic', '-Os', '-g',
        '-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-fno-unwind-tables',
        '-fno-asynchronous-unwind-tables', '-nostdlib', '-ffunction-sections', '-fdata-sections',
        '-Wl,--gc-sections', '-Wl,--no-undefined', '-Wl,--build-id=none', '-Wl,-z,noexecstack',
        '-Wl,-z,max-page-size=4096', '-Wl,-z,common-page-size=4096',
        '-I', str(output), '-I', str(APP / 'native'), '-I', str(APP / 'workflow')]
    commands = []
    env = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(output / 'zig-global-cache'),
               ZIG_LOCAL_CACHE_DIR=str(output / 'zig-local-cache'))

    def compile(source, destination, extra):
        command = [str(COMPILER), 'cc', *common, *extra, str(source), '-o', str(output / destination)]
        commands.append(command)
        result = subprocess.run(command, capture_output=True, text=True, timeout=120, env=env)
        (output / (destination + '.compile.log')).write_text(result.stdout + result.stderr)
        require(result.returncode == 0, 'Cross-compilation failed: ' + result.stderr[-3000:])

    compile(ROOT / 'native/install_volatile_patch.c', 'worker.debug.elf', ['-static', '-fno-pic', '-Wl,-e,_start'])
    debug = (output / 'worker.debug.elf').read_bytes()
    elf = ELFFile(io.BytesIO(debug))
    limit = max(s['p_offset'] + s['p_filesz'] for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD')
    compact = bytearray(debug[:limit])
    struct.pack_into('<Q', compact, 40, 0)
    struct.pack_into('<3H', compact, 58, 0, 0, 0)
    (output / 'worker.elf').write_bytes(compact)
    (output / 'worker_blob.h').write_text(array('worker_blob', compact))
    symbols = {s.name: s['st_value'] for s in elf.get_section_by_name('.symtab').iter_symbols() if s.name}
    (output / 'symbols.json').write_text(json.dumps(symbols, indent=2) + '\n')
    compile(APP / 'native/bootstrap.c', 'libJit.so', ['-shared', '-fPIC', '-Wl,-Bsymbolic', '-s'])
    require((output / 'libJit.so').stat().st_size <= 65520, 'Bootstrap exceeds single-upload bound')
    require((output / 'libJit.so').read_bytes().count(bytes(compact)) == 1, 'Worker embedding count differs')
    require(input_evidence() == (sources, libraries), 'Sources/ELFs changed during build')
    names = ('job.h', 'worker.debug.elf', 'worker.elf', 'worker_blob.h', 'symbols.json', 'libJit.so',
             'worker.debug.elf.compile.log', 'libJit.so.compile.log')
    manifest = {'schema': SCHEMA, 'profile': PROFILE, 'admission': 'OFFLINE_NOT_BODY_BOUND',
        'live_controller_sealed': False, 'target_package_sha256': None, 'body_binding': None,
        'hardware_operations': 0, 'hardware_acceptance': False, 'native_fault_model_executed': False,
        'worker_executed': False, 'bootstrap_executed': False, 'automatic_retry': False,
        'nonce': nonce.hex(), 'job_dir': job_dir, 'sources': sources, 'libraries': libraries,
        'compiler': {'path': str(COMPILER.relative_to(ROOT)), 'sha256': COMPILER_SHA,
                     'version': '0.15.2', 'host': 'aarch64-macos', 'target': 'aarch64-linux-gnu'},
        'compile_commands': commands,
        'artifacts': {name: {'bytes': (output / name).stat().st_size, 'sha256': sha(output / name)} for name in names},
        'result': {'magic': MAGIC, 'version': VERSION, 'start_magic': START_MAGIC,
                   'start_version': START_VERSION, 'format': '<8s16s51q', 'bytes': 432, 'fields': list(FIELDS)},
        'timeouts': {'start': 120, 'maps_wait': 300}, 'patch_order': ['app', 'lib'],
        'partial_failure_restore_order': ['lib', 'app'], 'success_phase': 7,
        'success_restores_RAM': False, 'success_requires_closed_mem_fds': True,
        'terminal_publication': {'pending': 'result.pending', 'published': 'result',
                                 'syscall': 'renameat2', 'flags': 1},
        'limitations': ['Offline compiler and ELF inspection do not prove real patch safety or install readiness',
            'Success intentionally leaves volatile instructions patched; no timed restoration',
            'No live identity, cache coherence, process lifecycle, renameat2 or tmpfs behavior validated',
            'No device executor, service handoff, firmware activation or installation authorization supplied',
            'Publication is volatile and requires a separately reviewed host-persisted receipt']}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = build(args.output)
    print(json.dumps({'output': str(output), 'manifest_sha256': sha(output / 'manifest.json'),
                      'module_bytes': (output / 'libJit.so').stat().st_size,
                      'admission': 'OFFLINE_NOT_BODY_BOUND', 'hardware_operations': 0}))


if __name__ == '__main__':
    main()
